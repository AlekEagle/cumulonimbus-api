import { Sequelize } from 'sequelize';

export let sequelize: Sequelize | null = null;

export async function init(): Promise<boolean> {
  if (!sequelize) {
    sequelize = new Sequelize({
      database: process.env.DATABASE,
      username: process.env.DATABASE_USER,
      password: process.env.DATABASE_PASS,
      host: process.env.DATABASE_HOST,
      port: Number(process.env.DATABASE_PORT),
      dialect: 'postgres',
      logging: false,
    });
    if (!(await testConnection()))
      throw new DBConnectionError('DB refused to connect.');
    return true;
  }
  return false;
}

export async function testConnection(): Promise<boolean> {
  if (!sequelize) throw new DBConnectionError('DB connection not initialized.');
  try {
    await sequelize.authenticate();
    return true;
  } catch (error) {
    console.error(error);
    return false;
  }
}

export class DBConnectionError extends Error {
  constructor(msg: string) {
    super(msg);

    Object.setPrototypeOf(this, DBConnectionError.prototype);
  }
}

export default {
  init,
  sequelize,
  testConnection,
  DBConnectionError,
};
