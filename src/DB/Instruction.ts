import { sequelize, init as initDB } from './index.js';
import logger from '../utils/LogMachine.js';

import { Model, DataTypes } from 'sequelize';

export enum InstructionStepActions {
  OPEN_URL = 'OPEN_URL',
  COPY_TOKEN_TO_CLIPBOARD = 'COPY_TOKEN_TO_CLIPBOARD',
  DOWNLOAD_CONFIG_FILE = 'DOWNLOAD_CONFIG_FILE',
  NOOP = 'NOOP',
}

export default class Instruction extends Model {
  declare id: string;
  declare name: string;
  declare steps: {
    action: InstructionStepActions;
    content: string;
    file?: {
      name: string;
      content: string;
    };
    url?: string;
  }[];
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
        type: DataTypes.ARRAY(DataTypes.JSONB),
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
