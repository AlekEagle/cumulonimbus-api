import { sequelize, init as initDB } from './index.js';
import logger from '../utils/LogMachine.js';

import { Model, DataTypes } from 'sequelize';

export default class Instruction extends Model {
  declare id: string;
  declare name: string;
  declare steps: string[];
  declare filename: string | null;
  declare content: string;
  declare description: string;
  declare createdAt: Date;
  declare updatedAt: Date;

  static is(value: any): value is Instruction {
    return value instanceof Instruction;
  }
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
      sequelize: sequelize!,
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
