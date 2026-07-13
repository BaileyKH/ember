import { Request, Response, NextFunction } from 'express'
import { respondWithJSON } from './json.js'
import { BadRequestError } from './errors.js' 
import { hashPassword } from '../auth.js'
import { ExistingUser } from '../db/schema.js'
import { createUser } from '../db/queries/users.js'

type PublicUser = Omit<ExistingUser, "hashedPassword">

export async function handlerUserCreate(req: Request, res: Response) {
    const { email, username, password } = req.body

    if (typeof email !== "string" || email.length === 0) {
        throw new BadRequestError("Please provide a valid email, username, and password")
    }

    if (typeof username !== "string" || username.length === 0) {
        throw new BadRequestError("Please provide a valid email, username, and password")
    }

    if (typeof password !== "string" || password.length < 8 ) {
        throw new BadRequestError("Password is too short. Try again")
    }

    const hashedPassword = await hashPassword(password)
    const newUser = await createUser({ email, username, hashedPassword })

    const publicUser: PublicUser = {
        id: newUser.id,
        createdAt: newUser.createdAt,
        updatedAt: newUser.updatedAt,
        email: newUser.email,
        profileImg: newUser.profileImg,
        username: newUser.username
    }

    respondWithJSON(201, publicUser)

}