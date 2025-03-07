declare module "*.json" {
  interface Config {
    clientId: string;
    clientSecret: string;
    redirectURL: string;
    serversToCheckRolesFor?: string[];
  }
  const value: Config;
  export default value;
}
