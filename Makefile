.PHONY: build

build:
	sam build

fmt:
	go fmt ./opa-authorizer/main.go

invoke:
	sam local invoke

deploy:
	sam build && sam deploy

delete:
	sam delete

destroy:
	aws cloudformation delete-stack --stack-name opa-http-golang-authorizer-stack