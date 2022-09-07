import express from "express"
import createError from "http-errors"
import { adminOnlyMiddleware } from "../../lib/auth/admin.js"
import { JWTAuthMiddleware } from "../../lib/auth/token.js"
import { createTokens, verifyRefreshAndCreateNewTokens } from "../../lib/auth/tools.js"
import UsersModel from "./model.js"

const usersRouter = express.Router()

usersRouter.post("/", async (req, res, next) => {
  try {
    const newUser = new UsersModel(req.body) // here mongoose validation happens
    const { _id } = await newUser.save() // here the validated record is saved
    res.status(201).send({ _id })
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/", JWTAuthMiddleware, async (req, res, next) => {
  try {
    const users = await UsersModel.find()
    res.send(users)
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    const user = await UsersModel.findById(req.user._id)
    if (user) {
      res.send(user)
    } else {
      next(createError(401, `User with id ${req.user._id} not found!`))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.put("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    const updatedUser = await UsersModel.findByIdAndUpdate(req.user._id, req.body, { new: true, runValidators: true })
    if (updatedUser) {
      res.send(updatedUser)
    } else {
      next(createError(404, `User with id ${req.params.userId} not found!`))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.delete("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    await UsersModel.findByIdAndDelete(req.user._id)
    res.status(204).send()
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/:userId", JWTAuthMiddleware, async (req, res, next) => {
  try {
    const user = await UsersModel.findById(req.params.userId)
    if (user) {
      res.send({ currentRequestingUser: req.user, user })
    } else {
      next(createError(404, `User with id ${req.params.userId} not found!`))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.put("/:userId", JWTAuthMiddleware, adminOnlyMiddleware, async (req, res, next) => {
  try {
    const updatedUser = await UsersModel.findByIdAndUpdate(req.params.userId, req.body, { new: true, runValidators: true })
    if (updatedUser) {
      res.send(updatedUser)
    } else {
      next(createError(404, `User with id ${req.params.userId} not found!`))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.delete("/:userId", JWTAuthMiddleware, adminOnlyMiddleware, async (req, res, next) => {
  try {
    const deletedUser = await UsersModel.findByIdAndDelete(req.params.userId)
    if (deletedUser) {
      res.status(204).send()
    } else {
      next(createError(404, `User with id ${req.params.userId} not found!`))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.post("/login", async (req, res, next) => {
  try {
    // 1. Obtain credentials from req.body
    const { email, password } = req.body

    // 2. Verify credentials
    const user = await UsersModel.checkCredentials(email, password)

    if (user) {
      // 3. If credentials are fine --> generate an access token (JWT) and send it back as a response
      const { accessToken, refreshToken } = await createTokens(user)
      res.send({ accessToken, refreshToken })
    } else {
      // 4. If credentials are NOT ok --> throw an error (401)
      next(createError(401, "Credentials are not ok!"))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.post("/refreshTokens", async (req, res, next) => {
  try {
    // 1. Obtain the current refresh token from req.body
    const { currentRefreshToken } = req.body

    // 2. Check the validity of that token (check if it is not expired, check if it hasn't been compromised, check if it is the same we have in db)
    // 3. If everything is fine --> generate a new pair of tokens (accessToken2 & refreshToken2), also replacing the previous refresh token with the new one in db
    const { accessToken, refreshToken } = await verifyRefreshAndCreateNewTokens(currentRefreshToken)
    // 4. Send the tokens back as a response
    res.send({ accessToken, refreshToken })
  } catch (error) {
    // 5. In case of errors --> 401
    next(error)
  }
})

export default usersRouter
