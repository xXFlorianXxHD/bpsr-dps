.PHONY: proto
proto:
	protoc -I . \
	--go_out=./pkg/pb --go_opt=paths=source_relative \
	--go-grpc_out=./pkg/pb --go-grpc_opt=paths=source_relative \
	proto/short.proto
#proto:
#	protoc -I . \
#	--go_out=./pkg/pb --go_opt=paths=source_relative \
#	--go-grpc_out=./pkg/pb --go-grpc_opt=paths=source_relative \
#	proto/bpsr.proto