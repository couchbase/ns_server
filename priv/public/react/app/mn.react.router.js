import { UIRouterReact, servicesPlugin, hashLocationPlugin } from "@uirouter/react";
import { UIRouterRx } from "@uirouter/rx";

const UIRouter = new UIRouterReact();

UIRouter.plugin(servicesPlugin);
UIRouter.plugin(hashLocationPlugin);
UIRouter.plugin(UIRouterRx);

export {UIRouter};