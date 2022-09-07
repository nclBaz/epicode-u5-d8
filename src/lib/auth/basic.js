import createHttpError from "http-errors"
import atob from "atob"
import UsersModel from "../../api/users/model.js"

export const basicAuthMiddleware = async (req, res, next) => {
  // This will be our "Police Officer Middleware" which is going to check "documents" of our users. If documents are ok user can have the access to the endpoint, otherwise user is going to receive an error
  // Here we are expecting to receive an Authorization header containing something like "Basic am9obkByYW1iby5jb206MTIzNA==", which is basically just email:password encoded into base64 format

  // 1. Check if Authorization header is provided, if it is not --> trigger an error (401)
  if (!req.headers.authorization) {
    next(createHttpError(401, "Please provide credentials in Authorization header!"))
  } else {
    // 2. If we have the Authorization header, we should extract the credentials out of it (credentials are base64 encoded therefore we should also decode them)
    const base64Credentials = req.headers.authorization.split(" ")[1] // --> "am9obkByYW1iby5jb206MTIzNA=="
    const decodedCredentials = atob(base64Credentials) // --> "john@rambo.com:1234"
    const [email, password] = decodedCredentials.split(":") // --> email=john@rambo.com, password=1234

    // 3. Once we obtain the credentials, it's now time to check if the user is in the db and if the provided password is ok
    const user = await UsersModel.checkCredentials(email, password)

    if (user) {
      // 4.a If credentials are ok --> you can go on
      req.user = user // I am attaching the current valid user to the request object
      next()
    } else {
      // 4.b If credentials are NOT ok --> trigger an error (401)
      next(createHttpError(401, "Credentials are wrong!"))
    }
  }
}
