import { sequelize, init as initDB } from './index.js';
import { logger } from '../index.js';
import { Model, DataTypes } from 'sequelize';

export default class File extends Model {
  id: string;
  userID: string;
  size: number;
  name: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

(async function () {
  await initDB();
  File.init(
    {
      id: {
        type: DataTypes.STRING,
        primaryKey: true,
        allowNull: false,
        unique: true,
      },
      userID: {
        type: DataTypes.STRING,
        allowNull: false,
        references: {
          model: 'Users',
          key: 'id',
        },
      },
      size: {
        type: DataTypes.INTEGER,
        allowNull: false,
      },
      name: {
        type: DataTypes.STRING(256),
        allowNull: true,
      },
    },
    {
      sequelize,
      tableName: 'Uploads',
    },
  );
  try {
    await File.sync();
    logger.info('Upload model synced with DB.');
  } catch (error) {
    logger.error('Unable to sync Upload model. Error: ', error);
  }
})();
