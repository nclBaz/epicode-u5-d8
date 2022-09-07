import mongoose from "mongoose"
import bcrypt from "bcrypt"

const { Schema, model } = mongoose

const UserSchema = new Schema(
  {
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["User", "Admin"], default: "User" },
  },
  {
    timestamps: true,
  }
)

UserSchema.pre("save", async function (next) {
  // BEFORE saving the user in db, execute a function (in this case hash the password)
  // I am NOT using an arrow function here because of "this" (it would be undefined in case of arrow function)

  const currentUser = this // In this case (pre save hook), "this" represents the current user I am trying to save in db

  const plainPW = currentUser.password

  if (currentUser.isModified("password")) {
    // only if the user is modifying the password (or if the user is being created) I would like to use some CPU cycles to calculate the hash, otherwise they would be just wasted

    const hash = await bcrypt.hash(plainPW, 11)
    currentUser.password = hash
  }

  next()
})

UserSchema.methods.toJSON = function () {
  // this .toJSON method will be used EVERY TIME Express does a res.send(user/s)
  // this does mean that we could override the default behaviour of this method to remove the password (and other unnecessary things) from the user/s and then return them

  const userDocument = this
  const user = userDocument.toObject()

  delete user.password
  delete user.__v
  return user
}

UserSchema.static("checkCredentials", async function (email, plainPassword) {
  // my own custom method attached to the UsersModel
  // Given email, plainPassword this method should search in db if the user exists (by email), then compare the given password with the hashed one coming from the db. Then return a useful response.

  // 1. Find the user by email
  const user = await this.findOne({ email }) // "this" here represents the UsersModel

  if (user) {
    console.log("USER: ", user)
    // 2. If the email is found --> compare plainPassword with the hashed one
    const isMatch = await bcrypt.compare(plainPassword, user.password)

    if (isMatch) {
      // 3. If passwords they do match --> return the user
      return user
    } else {
      return null
    }
  } else {
    // 4. In case of either email not found or password not correct --> return null
    return null
  }
})

export default model("User", UserSchema)
