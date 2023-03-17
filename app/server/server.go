/*
 * Copyright 2023 OpsMx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/OpsMx/go-app-base/version"
	"github.com/opsmx/oes-birger/internal/serviceconfig"
	pb "github.com/opsmx/oes-birger/internal/tunnel"
	"github.com/opsmx/oes-birger/internal/ulid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type server struct {
	pb.UnimplementedTunnelServiceServer
	sync.Mutex
	agentIdleTimeout int64
	streamManager    *StreamManager
}

type serviceRequest struct {
	req       *pb.TunnelRequest
	echo      serviceconfig.HTTPEcho
	closechan chan bool
}

func (s *server) Hello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloResponse, error) {
	agentID, _ := IdentityFromContext(ctx)
	_, logger := loggerFromContext(ctx)
	sessionID := ulid.GlobalContext.Ulid()
	logger.Infow("Hello", "endpoints", in.Endpoints, "agentInfo.annotations", in.AgentInfo.Annotations, "sessionID", sessionID)
	session := agents.registerSession(agentID, sessionID, in.Hostname, in.Version, in.AgentInfo, in.Endpoints)
	return &pb.HelloResponse{
		InstanceId: session.SessionID,
		AgentId:    agentID,
		Version:    version.VersionString(),
	}, nil
}

func (s *server) Ping(ctx context.Context, in *pb.PingRequest) (*pb.PingResponse, error) {
	session, err := agents.findSession(ctx)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "Hello must be called first")
	}
	now := time.Now().UnixNano()
	agents.touchSession(session, now)
	r := &pb.PingResponse{
		Ts:       uint64(now),
		EchoedTs: in.Ts,
	}
	return r, nil
}

func (s *server) closeAgentSession(ctx context.Context, session *AgentContext) {
	agents.removeSession(session)
	s.streamManager.FlushAgent(ctx, session)
}

func (s *server) WaitForRequest(in *pb.WaitForRequestArgs, stream pb.TunnelService_WaitForRequestServer) error {
	ctx, logger := loggerFromContext(stream.Context())
	session, err := agents.findSession(stream.Context())
	if err != nil {
		return status.Error(codes.FailedPrecondition, "Hello must be called first")
	}
	defer agents.removeSession(session)

	for {
		select {
		case <-ctx.Done():
			logger.Infow("closed connection")
			s.closeAgentSession(ctx, session)
			return status.Error(codes.Canceled, "client closed connection")
		case sr := <-session.out:
			s.streamManager.Register(ctx, session, sr.req.StreamId, sr.closechan, sr.echo)
			if err := stream.Send(sr.req); err != nil {
				s.closeAgentSession(ctx, session)
				logger.Errorw("WaitForRequest stream.Send() failed, dropping agent", "error", err)
				return status.Error(codes.Canceled, "send failed")
			}
		}
	}
}

func (s *server) done(ctx context.Context, stream *Stream) {
	if err := stream.echo.Done(ctx); err != nil {
		_ = stream.echo.Fail(ctx, http.StatusTeapot, err)
	}
}

func (s *server) getStreamAndID(ctx context.Context, event *pb.StreamFlow) (string, *Stream, error) {
	var streamID string
	if sid, ok := event.Event.(*pb.StreamFlow_StreamId); !ok {
		return "", nil, status.Error(codes.InvalidArgument, "first message must be streamID")
	} else {
		streamID = sid.StreamId
	}
	stream, streamFound := s.streamManager.Find(ctx, streamID)
	if !streamFound {
		return "", nil, status.Error(codes.InvalidArgument, "no such streamID")
	}
	return streamID, stream, nil
}

func (s *server) DataFlowAgentToController(rpcstream pb.TunnelService_DataFlowAgentToControllerServer) error {
	ctx := rpcstream.Context()

	event, err := rpcstream.Recv()
	if err != nil {
		return status.Error(codes.InvalidArgument, "unable to read streamID")
	}
	streamID, stream, err := s.getStreamAndID(ctx, event)
	if err != nil {
		return err
	}
	ctx, logger := loggerFromContext(ctx, zap.String("streamID", streamID))
	defer s.streamManager.Unregister(ctx, streamID)

	for {
		event, err := rpcstream.Recv()
		if err == io.EOF {
			s.done(ctx, stream)
			return nil
		}
		if err != nil {
			logger.Infof("stream error: %v", err)
			if serr, ok := status.FromError(err); ok {
				if serr.Code() == codes.Canceled {
					return nil
				}
			}
			_ = stream.echo.Fail(ctx, http.StatusTeapot, err)
			return err
		}

		switch event.Event.(type) {
		case *pb.StreamFlow_Cancel:
			_ = stream.echo.Cancel(ctx)
			return nil
		case *pb.StreamFlow_Done:
			_ = stream.echo.Done(ctx)
			return nil
		case *pb.StreamFlow_Headers:
			_ = stream.echo.Headers(ctx, event.GetHeaders())
		case *pb.StreamFlow_Data:
			_ = stream.echo.Data(ctx, event.GetData().Data)
		}
	}
}

func runAgentGRPCServer(ctx context.Context, useTLS bool, serverCert *tls.Certificate) {
	ctx, logger := loggerFromContext(ctx, zap.String("component", "grpcServer"))
	logger.Infow("starting agent GRPC server", "port", config.AgentListenPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", config.AgentListenPort))
	if err != nil {
		logger.Fatalw("failed to listen on agent port", "error", err)
	}

	idleTimeout := 60 * time.Second

	s := &server{
		agentIdleTimeout: idleTimeout.Nanoseconds(),
		streamManager:    NewStreamManager(),
	}

	cleanerCtx, cleanerCancel := context.WithCancel(ctx)
	defer cleanerCancel()
	go agents.checkSessionTimeouts(cleanerCtx, s.agentIdleTimeout)

	certPool, err := authority.MakeCertPool()
	if err != nil {
		logger.Fatalw("authority.MakeCertPool", "error", err)
	}
	creds := credentials.NewTLS(&tls.Config{
		ClientCAs:    certPool,
		ClientAuth:   tls.NoClientCert,
		Certificates: []tls.Certificate{*serverCert},
		MinVersion:   tls.VersionTLS13,
	})
	interceptor := NewJWTInterceptor()
	opts := []grpc.ServerOption{
		grpc.Creds(creds),
		grpc.KeepaliveEnforcementPolicy(kaep),
		grpc.KeepaliveParams(kasp),
		grpc.UnaryInterceptor(interceptor.Unary()),
		grpc.StreamInterceptor(interceptor.Stream()),
	}
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterTunnelServiceServer(grpcServer, s)
	if err := grpcServer.Serve(lis); err != nil {
		logger.Fatalw("grpcServer.Serve() failed", "error", err)
	}
}
