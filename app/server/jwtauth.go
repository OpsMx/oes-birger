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
	"fmt"

	"github.com/opsmx/oes-birger/internal/jwtutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TODO: for now, this will just be a simple "I trust you" interceptor.

type ContextTypes int

const (
	ContextSessionID ContextTypes = iota
	ContextAgentID
)

type JWTInterceptor struct{}

func NewJWTInterceptor() *JWTInterceptor {
	return &JWTInterceptor{}
}

func IdentityFromContext(ctx context.Context) (string, string) {
	sessionID := ctx.Value(ContextSessionID)
	if sessionID == nil {
		sessionID = ""
	}
	agentID := ctx.Value(ContextAgentID)
	if agentID == nil {
		agentID = ""
	}

	return agentID.(string), sessionID.(string)
}

func (interceptor *JWTInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		agentID, sessionID, err := interceptor.authorize(ctx)
		if err != nil {
			return nil, err
		}
		ctx = context.WithValue(ctx, ContextAgentID, agentID)
		ctx = context.WithValue(ctx, ContextSessionID, sessionID)
		return handler(ctx, req)
	}
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (ss *serverStream) Context() context.Context {
	return ss.ctx
}

func (interceptor *JWTInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := stream.Context()
		agentID, sessionID, err := interceptor.authorize(ctx)
		if err != nil {
			return err
		}
		ctx = context.WithValue(ctx, ContextAgentID, agentID)
		ctx = context.WithValue(ctx, ContextSessionID, sessionID)
		return handler(srv, &serverStream{ServerStream: stream, ctx: ctx})
	}
}

func (interceptor *JWTInterceptor) authorize(ctx context.Context) (string, string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", "", fmt.Errorf("unable to read headers from request metadata")
	}

	authorizationValues := md["authorization"]
	if len(authorizationValues) == 0 {
		return "", "", status.Errorf(codes.Unauthenticated, "authorization header missing or invalid")
	}

	agentID, err := jwtutil.ValidateAgentJWT(authorizationValues[0], nil)
	if err != nil {
		return "", "", status.Errorf(codes.Unauthenticated, "cannot validate JWT")
	}

	// TODO: check JWT, extract agent

	sessionValues := md["x-session-id"]
	sessionID := ""
	if len(sessionValues) != 0 {
		sessionID = sessionValues[0]
	}

	return agentID, sessionID, nil
}
