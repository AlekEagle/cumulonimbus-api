import { sequelize, init as initDB } from '.';
import { Model, DataTypes } from 'sequelize';

export default class Domain extends Model {
  domain: string;
  allowsSubdomains: boolean;
  createdAt: Date;
  updatedAt: Date;
}

(async function () {
  await initDB();
  Domain.init(
    {
      domain: {
        type: DataTypes.STRING,
        primaryKey: true
      },
      allowsSubdomains: DataTypes.BOOLEAN
    },
    {
      sequelize,
      tableName: 'Domains'
    }
  );
  try {
    await Domain.sync();
    console.log('Domain table synced with DB.');
  } catch (error) {
    console.error('Unable to sync Domain table. Error: ', error);
  }
})();
