import { Request, Response, NextFunction } from 'express'
import { BadRequestError } from './errors.js' 
import { hashPassword } from '../auth.js'
import { ExistingUser } from '../db/schema.js'
import { createUser } from '../db/queries/users.js'
import { validateNewPassword } from '../passwordPolicy.js'

export type PublicUser = Omit<ExistingUser, "hashedPassword" | "sessionVersion">

export async function handlerUserCreate(req: Request, res: Response) {
    const { email, username, password } = req.body

    if (typeof email !== "string" || email.length === 0) {
        throw new BadRequestError("Please provide a valid email, username, and password")
    }

    if (typeof username !== "string" || username.length === 0) {
        throw new BadRequestError("Please provide a valid email, username, and password")
    }

    const normalizedEmail = email.toLowerCase().trim()
    const trimmedUsername = typeof username === "string" ? username.trim() : ""
    if (!/^[a-zA-Z0-9_]{3,30}$/.test(trimmedUsername)) {
        throw new BadRequestError("Username must be 3-30 characters (letters, numbers, underscores)")
    }
    await validateNewPassword(password, {
        email: normalizedEmail,
        username: trimmedUsername,
    })
    const hashedPassword = await hashPassword(password)

    try {
        const newUser = await createUser({ email: normalizedEmail, username: trimmedUsername, hashedPassword })

        const publicUser: PublicUser = {
            id: newUser.id,
            createdAt: newUser.createdAt,
            updatedAt: newUser.updatedAt,
            email: newUser.email,
            profileImg: newUser.profileImg,
            username: newUser.username
        }

        return res.status(201).json(publicUser)

    } catch (err: any) {
        if (err.cause?.code === '23505' || err.code === '23505') {
            const constraint = err.cause?.constraint_name ?? err.constraint_name ?? err.constraint ?? '';
            if (constraint.includes('email')) {
                throw new BadRequestError("Email already in use");
            }
            if (constraint.includes('username')) {
                throw new BadRequestError("Username already taken");
            }
            throw new BadRequestError("Email or username already in use");
        }
        throw err
    }

}
