.PHONY: proto
proto:
	protoc \
	-I proto -I proto/zproto \
	--go_out=paths=source_relative:./pkg/pb \
	--go-grpc_out=paths=source_relative:./pkg/pb \
	proto/bpsr/ffs.proto
#	protoc -I . -I proto/zproto/* -I proto/bpsr/* \
#	--go_out=./pkg/pb --go_opt=paths=source_relative \
#	--go-grpc_out=./pkg/pb --go-grpc_opt=paths=source_relative \
#	proto/bpsr/ffs.proto
#proto:
#	protoc -I . \
#	--go_out=./pkg/pb --go_opt=paths=source_relative \
#	--go-grpc_out=./pkg/pb --go-grpc_opt=paths=source_relative \
#	proto/bpsr.proto