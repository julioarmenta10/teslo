import { createParamDecorator } from '@nestjs/common';

export const GetUser = createParamDecorator(() => {
  return 'hola mundo';
});
