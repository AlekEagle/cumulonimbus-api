import { sequelize, init as initDB } from './index.js';
import { logger } from '../index.js';
import { PermissionFlags } from '../middleware/SessionPermissionChecker.js';

import { Model, DataTypes } from 'sequelize';

export default class Session extends Model {
  id!: string;
  user!: string;
  exp!: Date;
  name!: string;
  permissionFlags!: PermissionFlags | null;
  usedAt!: null | Date; // This is a nullable field
  createdAt!: Date;
  updatedAt!: Date;

  static is(value: any): value is Session {
    return 'id' in value && 'user' in value && 'exp' in value;
  }
}

(async function () {
  await initDB();
  Session.init(
    {
      id: {
        type: DataTypes.STRING,
        primaryKey: true,
        allowNull: false,
        unique: true,
      },
      user: {
        type: DataTypes.STRING,
        allowNull: false,
        primaryKey: true,
        references: {
          key: 'id',
          model: 'Users',
        },
      },
      exp: {
        type: DataTypes.DATE,
        allowNull: false,
      },
      name: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      permissionFlags: {
        type: DataTypes.INTEGER,
        allowNull: true,
      },
      usedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
    },
    {
      sequelize: sequelize!,
      tableName: 'Sessions',
    },
  );
  try {
    await Session.sync();
    logger.info('Session model synced with DB.');
  } catch (error) {
    logger.error('Unable to sync User model. Error: ', error);
  }
})();
