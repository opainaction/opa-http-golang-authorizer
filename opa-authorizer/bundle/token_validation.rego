package visaeasy.awslambdaauthorizer.authz

import data.security.jwks
import input.authorization as authz_header

valid_token {
  access_token := split(authz_header, "Bearer ")[1]
  io.jwt.verify_rs256(access_token, json.marshal(jwks))
}
