import { Cumulonimbus } from '../types';
import UserSessionEndpoints from './user/UserSessionEndpoints';
import UserAccountEndpoints from './user/UserAccountEndpoints';
import UserFileEndpoints from './user/UserFileEndpoints';
import AdminAccountEndpoints from './admin/AdminAccountEndpoints';

const Endpoints: Cumulonimbus.APIEndpointModule[] = [
  UserAccountEndpoints,
  UserSessionEndpoints,
  UserFileEndpoints,
  AdminAccountEndpoints
];

export default Endpoints;
