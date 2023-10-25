import { sequelize, init as initDB } from './index.js';
import { Model, DataTypes } from 'sequelize';
import { logger } from '../index.js';

export default class User extends Model {
  id: string;
  username: string;
  email: string;
  verified: boolean;
  password: string;
  sessions: {
    iat: number;
    exp: number;
    name: string;
  }[];
  staff: boolean;
  domain: string;
  subdomain: string | null;
  bannedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

(async function () {
  await initDB();
  User.init(
    {
      id: {
        type: DataTypes.STRING,
        primaryKey: true,
        allowNull: false,
        unique: true,
      },
      username: {
        type: DataTypes.STRING(64),
        allowNull: false,
        unique: true,
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
      },
      verified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        allowNull: false,
      },
      password: {
        type: DataTypes.STRING(60),
        allowNull: false,
      },
      sessions: {
        type: DataTypes.ARRAY(DataTypes.JSONB),
        defaultValue: [],
        allowNull: false,
      },
      staff: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        allowNull: false,
      },
      domain: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      subdomain: {
        type: DataTypes.STRING(64),
        allowNull: true,
      },
      bannedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
    },
    {
      sequelize,
      tableName: 'Users',
    },
  );
  try {
    await User.sync();
    logger.log('User table synced with DB.');
  } catch (error) {
    logger.error('Unable to sync User table. Error: ', error);
  }
})();
