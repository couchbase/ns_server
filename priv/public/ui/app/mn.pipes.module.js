import * as pipes from './mn.pipes.js';
import { NgModule } from '../web_modules/@angular/core.js';
import { DecimalPipe } from '../web_modules/@angular/common.js';

export { MnPipesModule };

class MnPipesModule {
  static get annotations() { return [
    new NgModule({
      declarations: [
        pipes.MnParseVersion,
        pipes.MnMBtoBytes,
        pipes.MnBytesToMB,
        pipes.MnObjectKeys,
        pipes.MnPrettyVersion,
        pipes.MnFormatProgressMessage,
        pipes.MnFormatStorageModeError,
        pipes.MnPrepareQuantity,
        pipes.MnFormatUptime,
        pipes.MnFormatQuantity,
        pipes.MnFormatWarmupMessage,
        pipes.MnBucketsType,
        pipes.MnTruncate
      ],
      exports: [
        pipes.MnParseVersion,
        pipes.MnMBtoBytes,
        pipes.MnBytesToMB,
        pipes.MnObjectKeys,
        pipes.MnPrettyVersion,
        pipes.MnFormatProgressMessage,
        pipes.MnFormatStorageModeError,
        pipes.MnPrepareQuantity,
        pipes.MnFormatUptime,
        pipes.MnFormatQuantity,
        pipes.MnFormatWarmupMessage,
        pipes.MnBucketsType,
        pipes.MnTruncate
      ],
      imports: [],
      providers: [
        pipes.MnParseVersion,
        pipes.MnPrettyVersion,
        pipes.MnPrepareQuantity,
        pipes.MnBytesToMB,
        pipes.MnFormatQuantity,
        DecimalPipe
      ]
    })
  ]}
}
