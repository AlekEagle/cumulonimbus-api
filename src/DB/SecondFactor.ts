import { sequelize, init as initDB } from './index.js';
import logger from '../utils/LogMachine.js';

import { Model, DataTypes } from 'sequelize';
import type {
  CredentialDeviceType,
  AuthenticatorTransport,
} from '@simplewebauthn/server';

export type SecondFactorType = 'totp' | 'webauthn';

export default class SecondFactor extends Model {
  declare id: string;
  declare user: string;
  declare type: SecondFactorType;
  declare name: string;
  // Fields used by TOTP
  declare secret: string | null;
  // Fields used by WebAuthn
  declare keyId: string | null;
  declare publicKey: Buffer | null;
  declare counter: number | null;
  declare deviceType: CredentialDeviceType | null;
  declare transports: AuthenticatorTransport[] | null;
  declare usedAt: Date | null;
  declare createdAt: Date;
  declare updatedAt: Date;

  static is(value: any): value is SecondFactor {
    return value instanceof SecondFactor;
  }
}

export async function initSecondFactor() {
  await initDB();
  SecondFactor.init(
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
        references: {
          model: 'Users',
          key: 'id',
        },
      },
      type: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      name: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      secret: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      keyId: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      publicKey: {
        type: DataTypes.BLOB,
        allowNull: true,
      },
      counter: {
        type: DataTypes.INTEGER,
        allowNull: true,
      },
      deviceType: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      transports: {
        type: DataTypes.ARRAY(DataTypes.STRING),
        allowNull: true,
      },
      usedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
    },
    {
      sequelize: sequelize!,
      tableName: 'SecondFactors',
    },
  );
  try {
    await SecondFactor.sync();
    logger.info('SecondFactor model synced with DB.');
  } catch (error) {
    logger.error('Unable to sync SecondFactor model. Error: ', error);
  }
}
