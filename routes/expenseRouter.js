import express from "express";
import { deleteTransaction, getTopExpenseCategories, getTotalExpenses, updateSavings, upsertTransactions } from "../controller/expenseController.js";
import { upload } from "../middlewares/uploadImage.js";

const expenseRouter = express.Router();

// Savings
expenseRouter.post('/upsert-savings', updateSavings);

// Transactions
expenseRouter.post('/upsert-transaction', upload.single("receipt"), upsertTransactions);
expenseRouter.delete('/delete-transaction/:id', deleteTransaction);
expenseRouter.post('/expenses-per-month', getTotalExpenses);
expenseRouter.get('/top-five-expenses', getTopExpenseCategories);



export default expenseRouter;