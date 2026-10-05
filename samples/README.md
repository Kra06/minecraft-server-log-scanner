# Sample logs
These are fake logs written to show what a Minecraft server log looks like, either when clean or when it's being attacked. A real server writes a file called latest.log while it runs.

Each line follows the pattern [time] [who wrote it/level]: message, and this fixed pattern is how the scanner distinguishes between lines.

every attack from a user to the server leaves a trace in the log. The scanner is meant to spot them - some can be seen in a single line, eg a Log4Shell message and others only show up when you look at many lines together, eg six wrong passwords by twelve bots

