import express from "express"
import listEndpoints from "express-list-endpoints"
import mongoose from "mongoose"
import cors from "cors"
import usersRouter from "./api/users/index.js"
import { forbiddenErrorHandler, genericErroHandler, notFoundErrorHandler, unauthorizedErrorHandler } from "./errorHandlers.js"

const server = express()
const port = process.env.PORT || 3001

// ********************************* MIDDLEWARES *****************************
server.use(cors())
server.use(express.json())

// ********************************** ENDPOINTS ******************************
server.use("/users", usersRouter)

// ******************************** ERROR HANDLERS ***************************
server.use(unauthorizedErrorHandler)
server.use(forbiddenErrorHandler)
server.use(notFoundErrorHandler)
server.use(genericErroHandler)

mongoose.connect(process.env.MONGO_CONNECTION_STRING)

mongoose.connection.on("connected", () => {
  console.log("Mongo Connected!")
  server.listen(port, () => {
    console.table(listEndpoints(server))
    console.log(`Server is listening on port ${port}`)
  })
})
