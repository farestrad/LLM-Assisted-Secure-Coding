//FACTORY PATTERN
export interface SecurityCheck {
    check(methodBody: string, methodName: string): string[];
}
