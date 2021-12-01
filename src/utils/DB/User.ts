import { sequelize, init as initDB } from '.';
import { Model, DataTypes } from 'sequelize';

export default class User extends Model {
  id: string;
  username: string;
  displayName: string;
  email: string;
  staff: string;
  password: string;
  domain: string;
  subdomain: string;
  bannedAt: string;
  createdAt: string;
  updatedAt: string;
  sessions: {
    sub: string;
    iat: number;
    eat: number;
    name: string;
  }[];
}

(async function () {
  await initDB();
  User.init(
    {
      id: {
        type: DataTypes.STRING,
        primaryKey: true
      },
      username: DataTypes.STRING(60),
      displayName: DataTypes.STRING(60),
      email: DataTypes.STRING,
      staff: DataTypes.STRING,
      password: DataTypes.STRING(2000),
      domain: DataTypes.STRING,
      subdomain: DataTypes.STRING,
      bannedAt: DataTypes.DATE,
      sessions: DataTypes.ARRAY(DataTypes.JSONB)
    },
    {
      sequelize,
      tableName: 'Users'
    }
  );
  try {
    await User.sync();
    console.log('User table synced with DB.');
  } catch (error) {
    console.error('Unable to sync User table. Error: ', error);
  }
})();
