import { sequelize, init as initDB } from './index.js';
import { logger } from '../index.js';
import { Model, DataTypes } from 'sequelize';

export default class Instruction extends Model {
  id: string;
  name: string;
  steps: string[];
  filename: string | null;
  content: string;
  description: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

(async function () {
  await initDB();
  Instruction.init(
    {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        allowNull: false,
        unique: true,
      },
      name: {
        type: DataTypes.STRING(64),
        allowNull: false,
      },
      steps: {
        type: DataTypes.ARRAY(DataTypes.STRING),
        allowNull: false,
      },
      filename: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      content: {
        type: DataTypes.STRING(65536),
        allowNull: false,
      },
      description: {
        type: DataTypes.STRING,
        allowNull: false,
      },
    },
    {
      sequelize,
      tableName: 'Instructions',
    },
  );
  try {
    await Instruction.sync();
    logger.info('Instruction model synced with DB.');
  } catch (error) {
    logger.error('Unable to sync Instruction model. Error: ', error);
  }
})();
