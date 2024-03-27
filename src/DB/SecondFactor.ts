import { sequelize, init as initDB } from './index.js';
import { logger } from '../index.js';

import { Model, DataTypes } from 'sequelize';
import type {
  CredentialDeviceType,
  AuthenticatorTransportFuture,
} from '@simplewebauthn/types';

export type SecondFactorType = 'totp' | 'webauthn';

export default class SecondFactor extends Model {
  id: string;
  user: string;
  type: SecondFactorType;
  name: string;
  // Fields used by TOTP
  secret?: string;
  // Fields used by WebAuthn
  keyId?: string;
  publicKey?: Buffer;
  counter?: number;
  deviceType?: CredentialDeviceType;
  transports?: AuthenticatorTransportFuture[];

  readonly createdAt: Date;
  readonly updatedAt: Date;
}

(async function () {
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
      },
      keyId: {
        type: DataTypes.STRING,
      },
      publicKey: {
        type: DataTypes.BLOB,
      },
      counter: {
        type: DataTypes.INTEGER,
      },
      deviceType: {
        type: DataTypes.STRING,
      },
      transports: {
        type: DataTypes.ARRAY(DataTypes.STRING),
      },
    },
    {
      sequelize,
      tableName: 'SecondFactors',
    },
  );
  try {
    await SecondFactor.sync();
    logger.info('SecondFactor model synced with DB.');
  } catch (error) {
    logger.error('Unable to sync SecondFactor model. Error: ', error);
  }
})();
