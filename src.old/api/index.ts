import { Cumulonimbus } from "..";
import UserSessionEndpoints from "./user/UserSessionEndpoints";
import UserAccountEndpoints from "./user/UserAccountEndpoints";
import UserFileEndpoints from "./user/UserFileEndpoints";
import AdminAccountEndpoints from "./admin/AdminAccountEndpoints";
import UploadEndpoint from "./user/UploadEndpoint";
import UserDomainEndpoints from "./user/UserDomainEndpoints";
import UserInstructionEndpoints from "./user/UserInstructionEndpoints";
import AdminDomainEndpoints from "./admin/AdminDomainEndpoints";
import AdminFileEndpoints from "./admin/AdminFileEndpoints";
import AdminInstructionEndpoints from "./admin/AdminInstructionEndpoints";
import AdminSessionEndpoints from "./admin/AdminSessionEndpoints";

const Endpoints: Cumulonimbus.APIEndpointModule[] = [
  UserAccountEndpoints,
  UserDomainEndpoints,
  UserFileEndpoints,
  UserInstructionEndpoints,
  UserSessionEndpoints,
  AdminAccountEndpoints,
  AdminDomainEndpoints,
  AdminFileEndpoints,
  AdminInstructionEndpoints,
  AdminSessionEndpoints,
  UploadEndpoint,
];

export default Endpoints;
