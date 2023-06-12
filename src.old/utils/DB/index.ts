import configureEnv from '../Env';
import { Sequelize } from 'sequelize';

export let sequelize: Sequelize = null;

export async function init(): Promise<boolean> {
  configureEnv();
  if (!sequelize) {
    sequelize = new Sequelize({
      database: process.env.SERVERDB,
      username: process.env.SERVERUSERNAME,
      password: process.env.SERVERPASSWORD,
      host: process.env.SERVERIP,
      port: 5432,
      dialect: 'postgres',
      logging: false
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
  DBConnectionError
};
