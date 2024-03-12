import { sequelize, init as initDB } from './index.js';
import { logger } from '../index.js';
import { Model, DataTypes } from 'sequelize';

export default class Domain extends Model {
  id: string;
  subdomains: boolean;
  createdAt: Date;
  updatedAt: Date;
}

(async function () {
  await initDB();
  Domain.init(
    {
      id: {
        type: DataTypes.STRING,
        primaryKey: true,
        allowNull: false,
      },
      subdomains: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        allowNull: false,
      },
    },
    {
      sequelize,
      tableName: 'Domains',
    },
  );
  try {
    await Domain.sync();
    logger.log('Domain model synced with DB.');
  } catch (error) {
    logger.error('Unable to sync Domain model. Error: ', error);
  }
})();
