import { sequelize, init as initDB } from './index.js';
import logger from '../utils/LogMachine.js';

import { Model, DataTypes } from 'sequelize';

export default class User extends Model {
  declare id: string;
  declare username: string;
  declare email: string;
  declare password: string;
  declare staff: boolean;
  declare domain: string;
  declare subdomain: string | null;
  declare verifiedAt: Date | null;
  declare bannedAt: Date | null;
  declare twoFactorBackupCodes: string[] | null;
  declare twoFactorBackupCodeUsedAt: Date | null;
  declare createdAt: Date;
  declare updatedAt: Date;
  declare deletingAt: Date | null;

  static is(value: any): value is User {
    return value instanceof User;
  }
}

export async function initUser() {
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
      password: {
        type: DataTypes.STRING(60),
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
      verifiedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      bannedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      twoFactorBackupCodes: {
        type: DataTypes.ARRAY(DataTypes.STRING(128)),
        allowNull: true,
      },
      twoFactorBackupCodeUsedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      deletingAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
    },
    {
      sequelize: sequelize!,
      tableName: 'Users',
    },
  );
  try {
    await User.sync();
    logger.info('User model synced with DB.');
  } catch (error) {
    logger.error('Unable to sync User model. Error: ', error);
  }
}
