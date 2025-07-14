import { z } from "zod";

// Validate signup form 
export const validateSignupFormData = z.object({
    name: z.string().min(1, "Name is required").optional(),
    email: z.string().email("Invalid email format"),
    password: z.string().min(6, "Password must be at least 6 characters"),
})

// Validate profile
export const validateProfileInfo = z.object({
    name: z.string().min(1, "Name is required"),
    income: z.coerce.number().nonnegative().optional(),
    goal: z.coerce.number().nonnegative().optional(),
});

// Transaction validation
export const validateTransactions = z.object({
    type: z.enum(["income", "expense"]),
    category: z.string().min(1),
    account: z.string().min(1),
    amount: z.coerce.number().positive("Amount must be greater than 0"),
    date: z.coerce.date().optional(),
    description: z.string().optional(),
    syncExpense: z.string().optional(),
});

// Savings validation
const savingItemSchema = z.object({
    method: z.string(),
    label: z.string(),
    amount: z.coerce.number().nonnegative().optional(),
});

// Email validation
export const validateEmail = z.object({
    email: z.string().email("Invalid email format"),
})

export const validateSavings = z.object({
    savings: z.record(z.array(savingItemSchema))
});
