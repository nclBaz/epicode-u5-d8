import createHttpError from "http-errors"
import jwt from "jsonwebtoken"
import UsersModel from "../../api/users/model.js"

export const createTokens = async user => {
  // 1. Given the user, it creates 2 tokens (accessToken & refreshToken)
  const accessToken = await createAccessToken({ _id: user._id, role: user.role })
  const refreshToken = await createRefreshToken({ _id: user._id })

  // 2. Save refreshToken in db
  user.refreshToken = refreshToken
  await user.save() // remember that user is a MONGOOSE DOCUMENT, therefore it has some special abilities like the .save() method

  // 3. Return the two tokens
  return { accessToken, refreshToken }
}

const createAccessToken = payload =>
  new Promise((resolve, reject) =>
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "15m" }, (err, token) => {
      if (err) reject(err)
      else resolve(token)
    })
  )

export const verifyAccessToken = token =>
  new Promise((res, rej) =>
    jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
      if (err) rej(err)
      else res(payload)
    })
  )

const createRefreshToken = payload =>
  new Promise((resolve, reject) =>
    jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "1 week" }, (err, token) => {
      if (err) reject(err)
      else resolve(token)
    })
  )

export const verifyRefreshToken = token =>
  new Promise((res, rej) =>
    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, payload) => {
      if (err) rej(err)
      else res(payload)
    })
  )

export const verifyRefreshAndCreateNewTokens = async currentRefreshToken => {
  try {
    // 1. Check expiration date and integrity of refresh token, we gonna catch potential errors
    const refreshPayload = await verifyRefreshToken(currentRefreshToken)

    // 2. If the token is valid, we shall check if it matches to the one we have in db
    const user = await UsersModel.findById(refreshPayload._id)
    if (!user) throw new createHttpError(404, `User with id ${refreshPayload._id} not found!`)

    if (user.refreshToken && user.refreshToken === currentRefreshToken) {
      // 3. If everything is fine --> create new tokens and return them
      const { accessToken, refreshToken } = await createTokens(user)
      return { accessToken, refreshToken }
    } else {
      throw new createHttpError(401, "Refresh Token not valid!")
    }
  } catch (error) {
    // 4. In case of troubles --> catch the error and send 401
    throw new createHttpError(401, "Refresh Token not valid!")
  }
}
