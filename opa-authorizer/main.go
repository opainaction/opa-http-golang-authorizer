package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"log"
)

var (
	//go:embed bundle/authz_policy.rego
	authzpolicy string
	//go:embed bundle/token_validation.rego
	tokenvalidation string
	//go:embed bundle/data.json
	data string

	store = inmem.NewFromReader(bytes.NewBufferString(data))

	ctx = context.Background()
)

func handler(request events.APIGatewayV2CustomAuthorizerV2Request) (events.APIGatewayV2CustomAuthorizerSimpleResponse, error) {
	fmt.Printf("Request %+v\n", request)

	query, err := rego.New(
		rego.Query("data.visaeasy.awslambdaauthorizer.authz.allow"),
		rego.Module("authz_policy.rego", authzpolicy),
		rego.Module("token_validation.rego", tokenvalidation),
		rego.Store(store),
	).PrepareForEval(ctx)

	if err != nil {
		log.Fatalf("Error preparing query: %s", err)
	}

	decision, err := query.Eval(ctx, rego.EvalInput(
		map[string]interface{}{
			"authorization": request.Headers["authorization"],
		}))
	if err != nil {
		log.Fatalf("Error evaluating query: %s", err)
	}

	fmt.Printf("Policy Decision %+v\n", decision)

	isAuthorized := decision.Allowed()

	return events.APIGatewayV2CustomAuthorizerSimpleResponse{
		IsAuthorized: isAuthorized,
		Context:      map[string]interface{}{},
	}, nil
}

func main() {
	lambda.Start(handler)
}
