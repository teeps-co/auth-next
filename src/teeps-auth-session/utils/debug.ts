import createDebug, { Debugger } from 'debug';

export default (name: string): Debugger => createDebug('next-teeps-auth').extend(name);
