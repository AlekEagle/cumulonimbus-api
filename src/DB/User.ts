import { sequelize, init as initDB } from './index.js';
import { logger } from '../index.js';

import { Model, DataTypes } from 'sequelize';

export default class User extends Model {
  id!: string;
  username!: string;
  email!: string;
  password!: string;
  staff!: boolean;
  domain!: string;
  subdomain!: string | null;
  verifiedAt!: Date | null;
  bannedAt!: Date | null;
  twoFactorBackupCodes!: string[] | null;
  twoFactorBackupCodeUsedAt!: Date | null;
  createdAt!: Date;
  updatedAt!: Date;

  static is(value: any): value is User {
    return value instanceof User;
  }
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
})();
