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

package logging

import (
	"context"
	"log"

	"go.uber.org/zap"
)

type loggerKeyType int

const (
	loggerKey loggerKeyType = iota
	fieldsKey
)

type loggerWrapper struct {
	logger *zap.Logger
	fields map[string]zap.Field
}

var defaultLogger *loggerWrapper

func init() {
	l, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("unable to create zap logger: %v", err)
	}
	defaultLogger = &loggerWrapper{
		logger: l,
		fields: map[string]zap.Field{},
	}
}

func values(fields map[string]zap.Field) []zap.Field {
	ret := []zap.Field{}
	for _, v := range fields {
		ret = append(ret, v)
	}
	return ret
}

func NewContext(ctx context.Context, fields ...zap.Field) context.Context {
	logger := withContext(ctx)
	newfields := map[string]zap.Field{}
	for k, v := range newfields {
		newfields[k] = v
	}
	for _, field := range fields {
		newfields[field.Key] = field
	}
	newLogger := &loggerWrapper{
		logger: logger.logger.With(values(newfields)...),
		fields: newfields,
	}
	return context.WithValue(ctx, loggerKey, newLogger)
}

func withContext(ctx context.Context) *loggerWrapper {
	if ctx == nil {
		return defaultLogger
	}
	if ctxLogger, ok := ctx.Value(loggerKey).(*loggerWrapper); ok {
		return ctxLogger
	}
	return defaultLogger
}

func WithContext(ctx context.Context) *zap.Logger {
	return withContext(ctx).logger
}
