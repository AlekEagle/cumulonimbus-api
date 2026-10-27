import { sequelize, init as initDB } from './index.js';
import logger from '../utils/LogMachine.js';

import { Model, DataTypes } from 'sequelize';

export default class File extends Model {
  declare id: string;
  declare userID: string;
  declare size: number;
  declare name: string;
  declare createdAt: Date;
  declare updatedAt: Date;

  static is(value: any): value is File {
    return value instanceof File;
  }
}

export async function initFile() {
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
      sequelize: sequelize!,
      tableName: 'Files',
    },
  );
  try {
    await File.sync();
    logger.info('File model synced with DB.');
  } catch (error) {
    logger.error('Unable to sync File model. Error: ', error);
  }
}
