import createHttpError from "http-errors"
import { verifyAccessToken } from "./tools.js"

export const JWTAuthMiddleware = async (req, res, next) => {
  // 1. Check if authorization header is in the request, if it is not --> 401
  if (!req.headers.authorization) {
    next(createHttpError(401, "Please provide Bearer token in the authorization header!"))
  } else {
    try {
      // 2. If authorization header is there, we should extract the token from it (Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MzE3MTBmNjkwZjM1NGQ0NDI4OTJkNGEiLCJpYXQiOjE2NjI1NDAxMDgsImV4cCI6MTY2MzE0NDkwOH0.cQ3xUMJD5CSgwyXaMw-6nnC33_bferZe_VhednUDnis")
      const token = req.headers.authorization.replace("Bearer ", "")

      // 3. Verify the token (check expiration date and check signature integrity), if everything is fine we should get back the payload { _id: "j12o3ijoi213jo123", role: "User" }
      const payload = await verifyAccessToken(token)

      // 4. If token is ok --> next

      req.user = {
        _id: payload._id,
        role: payload.role,
      }

      next()
    } catch (error) {
      // 5. If token is NOT ok jsonwebtoken library should throw some errors, so we gonna catch'em and --> 401
      console.log(error)
      next(createHttpError(401, "Token not valid!"))
    }
  }
}
