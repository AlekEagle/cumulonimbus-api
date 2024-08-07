import { sequelize, init as initDB } from './index.js';
import { logger } from '../index.js';

import { Model, DataTypes } from 'sequelize';

export default class GlobalKillSwitches extends Model {
  id!: number;
  state!: boolean;
  createdAt!: Date;
  updatedAt!: Date;

  static is(value: any): value is GlobalKillSwitches {
    return value instanceof GlobalKillSwitches;
  }
}

(async function () {
  await initDB();
  GlobalKillSwitches.init(
    {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        allowNull: false,
        unique: true,
      },
      state: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
    },
    {
      sequelize: sequelize!,
      modelName: 'GlobalKillSwitches',
      createdAt: false,
      updatedAt: false,
    },
  );
  try {
    await GlobalKillSwitches.sync();
    logger.info('GlobalKillSwitches model synced with DB.');
  } catch (error) {
    logger.error('Unable to sync GlobalKillSwitches model. Error:', error);
  }
})();
