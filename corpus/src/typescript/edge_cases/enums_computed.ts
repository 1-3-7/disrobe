export const enum Status {
    Active = 1,
    Inactive = 0,
    Pending = Active | Inactive,
    Archived = Active << 2,
}

export enum FilePermissions {
    None = 0,
    Read = 1 << 0,
    Write = 1 << 1,
    Execute = 1 << 2,
    All = Read | Write | Execute,
}

export enum LogLevel {
    Trace = "TRACE",
    Debug = "DEBUG",
    Info = "INFO",
    Warn = "WARN",
    Error = "ERROR",
}

export function has(mask: FilePermissions, flag: FilePermissions): boolean {
    return (mask & flag) === flag;
}

export const sample = has(FilePermissions.All, FilePermissions.Execute);
export const level: LogLevel = LogLevel.Info;
export const status: Status = Status.Active;
