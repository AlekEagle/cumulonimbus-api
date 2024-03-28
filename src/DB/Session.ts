import { sequelize, init as initDB } from './index.js';
import { logger } from '../index.js';
import { PermissionFlags } from '../utils/Session.js';

import { Model, DataTypes } from 'sequelize';

export default class Session extends Model {
  id: string;
  user: string;
  exp: Date;
  name: string;
  permissionFlags: PermissionFlags;
  usedAt: Date;
  readonly createdAt: Date;
  readonly updatedAt: Date;
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
        allowNull: false,
        // Default to ALL permissions
        defaultValue: PermissionFlags.ALL,
      },
      usedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
    },
    {
      sequelize,
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
