import { sequelize, init as initDB } from './index.js';
import { logger } from '../index.js';

import { Model, DataTypes } from 'sequelize';
import type {
  CredentialDeviceType,
  AuthenticatorTransportFuture,
} from '@simplewebauthn/types';

export type SecondFactorType = 'totp' | 'webauthn';

export default class SecondFactor extends Model {
  id!: string;
  user!: string;
  type!: SecondFactorType;
  name!: string;
  // Fields used by TOTP
  secret!: string | null;
  // Fields used by WebAuthn
  keyId!: string | null;
  publicKey!: Buffer | null;
  counter!: number | null;
  deviceType!: CredentialDeviceType | null;
  transports!: AuthenticatorTransportFuture[] | null;
  createdAt!: Date;
  updatedAt!: Date;

  static is(value: any): value is SecondFactor {
    return value instanceof SecondFactor;
  }
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
})();
