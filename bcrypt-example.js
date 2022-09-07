import bcrypt from "bcrypt"

const plainPW = "1234"

const numberOfRounds = 12 // rounds=10 --> algorithm will be calculated 2^10 times = 1024 times

console.log(`The algorithm will be calculated 2^${numberOfRounds} times --> ${Math.pow(2, numberOfRounds)} times`)

console.time("hashing")
const hashedPW = bcrypt.hashSync(plainPW, numberOfRounds) // SALTED HASH --> bcrypt library doesn't simply hash("1234"), instead it generates a random string like "Bl4LiRBh/BceGk4zZQg9Gu.xubh" and calculates the hash("Bl4LiRBh/BceGk4zZQg9Gu.xubh"+"1234"), this will lead to a different result every time you run the function on the same password (NON DETERMINISTIC HASH!)
console.timeEnd("hashing")

console.log("HASH: ", hashedPW)

const isOK = bcrypt.compareSync(plainPW, hashedPW)

console.log("DO THEY MATCH? ", isOK)
