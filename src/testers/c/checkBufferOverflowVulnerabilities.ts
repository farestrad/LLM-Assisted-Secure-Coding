import * as vscode from 'vscode';
import Parser from 'tree-sitter';
import C from 'tree-sitter-c';
import { SecurityCheck } from "../c/SecurityCheck";

let parser: Parser;

function initParser() {
    if (!parser) {
        parser = new Parser();
        parser.setLanguage(C as unknown as Parser.Language);
    }
}

export class BufferOverflowCheck implements SecurityCheck {
    check(methodBody: string, methodName: string): string[] {
        const issues: string[] = [];
        const buffers = new Map<string, number>();
        const validationChecks = new Set<string>();
        const validationFunctions = new Set<string>();
        const calledFunctions = new Set<string>();
        const aliases = new Map<string, string>()
        const mallocAssigned = new Set<string>();
        const mallocChecked = new Set<string>();
        const visited = new Set<Parser.SyntaxNode>();
        const unsafeFunctions = new Map<string, string>([
            ['strcpy', 'strncpy'],
            ['strcat', 'strncat'],
            ['gets', 'fgets'],
            ['sprintf', 'snprintf'],
            ['vsprintf', 'vsnprintf'],
            ['gets_s', 'fgets'],
            ['scanf', 'fgets with parsing or use "%Ns"'],
            ['strtok', 'strtok_r'],
            ['asctime', 'asctime_r'],
            ['ctime', 'ctime_r'],
            ['tmpnam', 'mkstemp'],
            ['tmpfile', 'tmpfile_s'],
            ['realpath', 'ensure buffer size is validated'],
        ]);
        



        const config = vscode.workspace.getConfiguration('securityAnalysis');
        const stackThreshold = config.get<number>('stackBufferThreshold', 512);

        initParser();
        const tree = parser.parse(methodBody);

        function extractSizeLiteral(node: Parser.SyntaxNode): number | null {
            if (!node) return null;
        
            if (node.type === 'number_literal') {
                return parseInt(node.text);
            }
        
            // Handle constant identifier (e.g., BUF_SIZE)
            if (buffers.has(node.text)) return buffers.get(node.text)!;
        
            return null;
        }
        

        function evaluateSimpleExpression(expr: string): number | null {
            try {
                return eval(expr.replace(/\b(\w+)\b/g, (_, v) => buffers.get(v)?.toString() || "0"));
            } catch {
                return null;
            }
        }

        function isValidatedByFunction(buffer: string): boolean {
            return Array.from(validationFunctions).some(fn =>
                new RegExp(`\\b${fn}\\s*\\(\\s*${buffer}\\s*\\)`).test(methodBody)
            );
        }

        function traverse(node: Parser.SyntaxNode) {
            if (visited.has(node)) return;
            visited.add(node);
             // FIRST: Recursively process children
            node.namedChildren.forEach(traverse);

            // THEN: Analyze current node
            if (node.type === 'if_statement') {
                const cond = node.childForFieldName('condition');
                const ids = cond?.descendantsOfType('identifier') || [];
                for (const id of ids) {
                    mallocChecked.add(id.text);
                    validationChecks.add(id.text);
                }

            }
            //  Buffer Declarations
            if (node.type === 'init_declarator') {
                const declaratorNode = node.childForFieldName('declarator');
                const valueNode = node.childForFieldName('value');
            
                if (declaratorNode && valueNode) {
                    const identifier = declaratorNode.descendantsOfType('identifier')[0];
                    const lhsName = identifier?.text || null;
                    const rhsName = valueNode.text || null;
            
                    if (
                        lhsName &&
                        rhsName &&
                        buffers.has(rhsName) &&
                        !/^\d+$/.test(rhsName) && // ignore numeric literals
                        !methodBody.includes(`(${rhsName}`) // crude param check: skip if rhs is a parameter
                    ) {
                        aliases.set(lhsName, rhsName);
                        buffers.set(lhsName, buffers.get(rhsName)!);
                    }
                    
            
            
                    // 🌟 Handle pointer arithmetic like: char *ptr = buf + 4;
                    if (valueNode.type === 'binary_expression') {
                        const op = valueNode.child(1)?.text;
                        const rhsLeft = valueNode.child(0);
                        const base = rhsLeft?.text;
            
                        if (
                            lhsName &&
                            base &&
                            ['+', '-'].includes(op || '') &&
                            (buffers.has(base) || aliases.has(base) || mallocAssigned.has(base))
                        ) {
                            const origin = buffers.has(base) ? base : aliases.get(base) || 'unknown';
                            issues.push(
                                `Warning: Pointer "${lhsName}" assigned with arithmetic on "${base}" (→ ${origin}) in "${methodName}"`
                            );
                        }
                    }
                }
            }
            
            
            
            
            
            if (node.type === 'declaration') {
                const declarator = node.childForFieldName('declarator');
                if (declarator?.type === 'array_declarator') {
                    const name = declarator.childForFieldName('declarator')?.text;
                    const sizeNode = declarator.childForFieldName('size');
                    let size: number | null = null;
                    if (sizeNode) {
                        size = extractSizeLiteral(sizeNode);
}

                    if (name && size !== null) {
                        buffers.set(name, size);
                        if (size > stackThreshold) {
                            issues.push(`Warning: Large stack buffer "${name}" (${size} bytes) in "${methodName}"`);
                        }
                    }
                }
            }

            //  Validation Function Identification
            if (node.type === 'function_definition') {
                const returnType = node.childForFieldName('type')?.text || '';
                const parameters = node.childForFieldName('declarator')?.descendantsOfType('parameter_declaration');
                if (['bool', 'int'].includes(returnType) && parameters?.some(p => /char\s*\*/.test(p.text))) {
                    const name = node.childForFieldName('declarator')?.descendantsOfType('identifier')[0]?.text;
                    if (name) validationFunctions.add(name);
                }
            }

            // Track variables assigned from malloc
            if (node.type === 'assignment_expression') {
                const lhs = node.child(0)?.text;
                const rhs = node.child(2);
                if (lhs && rhs?.type === 'call_expression' && rhs.child(0)?.text === 'malloc') {
                    mallocAssigned.add(lhs);
                }
            }
        

        
           
            //  Call Expression Handling
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text;
                const args = node.child(1)?.namedChildren.map(c => c.text) || [];

                if (fnName && unsafeFunctions.has(fnName)) {
                    const safer = unsafeFunctions.get(fnName);
                    issues.push(
                        `Warning: Use of unsafe function "${fnName}" in "${methodName}". Consider the safer alternative: "${safer}"`
                    );
                }
                
                // Validation tracking
                if (['strlen', 'sizeof', '_countof'].includes(fnName || '')) {
                    args.forEach(arg => validationChecks.add(arg));
                }

                const buffer = args[0]; // first argument is usually the destination buffer

                const shouldValidateSize = ['strncpy', 'strncat', 'snprintf', 'memcpy', 'memmove'].includes(fnName || '');

                if (
                    shouldValidateSize &&
                    buffer &&
                    !validationChecks.has(buffer) &&
                    !isValidatedByFunction(buffer) &&
                    !mallocChecked.has(buffer)
                ) {
                    if (fnName === 'strncpy') {
                        const dest = args[0];
                        const sizeArg = args[2];
                    
                        const isValidated =
                            validationChecks.has(sizeArg) || /sizeof|strlen/.test(sizeArg);
                    
                        if (!isValidated) {
                            //issues.push(
                            //    `Warning: Unvalidated size parameter in strncpy to "${dest}" in "${methodName}"`
                          //  );
                        }
                    
                        if (!validationChecks.has(dest) && !isValidatedByFunction(dest)) {
                            //issues.push(
                                //`Warning: Possible unsafe usage of "${fnName}" with "${dest}" in "${methodName}". Destination is not validated.`
                            //);
                        }
                    }
                    
}


                // 🎯 Format string with %s + literal injection estimation
                if (
                    ['sprintf', 'snprintf'].includes(fnName || '') &&
                    args.length >= 2
                ) {
                    const destBuffer = args[0];
                    const formatArg = node.child(1)?.namedChildren[1];
                    const secondArg = node.child(1)?.namedChildren[2];

                    if (
                        destBuffer &&
                        formatArg?.type === 'string_literal' &&
                        secondArg?.type === 'string_literal' &&
                        buffers.has(destBuffer)
                    ) {
                        const format = formatArg.text;
                        const injected = secondArg.text;
                        const formatLen = format.length - 2;  // strip quotes
                        const injectedLen = injected.length - 2;

                        const totalSize = formatLen + injectedLen - 2; // rough guess, minus %s

                        const bufferSize = buffers.get(destBuffer)!;
                        if (totalSize > bufferSize) {
                            issues.push(
                                `Warning: sprintf format string + argument may overflow buffer "${destBuffer}" (${bufferSize} bytes) in method "${methodName}". Estimated size: ${totalSize}`
                            );
                        }
                    }
                }



                // Allocation size validation
                if (['malloc'].includes(fnName || '') && args.length === 1) {
                    const sizeArg = args[0];
                    const trimmed = sizeArg.trim();
                    console.log(`[DEBUG] malloc sizeArg="${sizeArg}" trimmed="${trimmed}"`);
                    console.log(`[DEBUG] validationChecks.has("${trimmed}") =`, validationChecks.has(trimmed));
                
                    if (!validationChecks.has(trimmed)) {
                        issues.push(`Warning: Untrusted allocation size "${trimmed}" in "${methodName}"`);
                    }
                }
                

                // Allocation return value check
                if (['malloc', 'calloc', 'realloc'].includes(fnName || '')) {
                    const assignedVar = node.parent?.type === 'assignment_expression' ? node.parent.child(0)?.text : null;
                    if (assignedVar && mallocAssigned.has(assignedVar) && !mallocChecked.has(assignedVar)) {
                        issues.push(`Warning: Unchecked return value of "${fnName}" in "${methodName}"`);
                    }
                }
                

                if (['memcpy', 'memmove'].includes(fnName || '') && args.length >= 3) {
                    const [destBuffer, , sizeExprText] = args;
                    const declaredSize = buffers.get(destBuffer);
                    const sizeLiteralNode = node.child(1)?.namedChildren[2];
                
                    let evaluatedSize: number | null = null;
                
                    if (sizeLiteralNode?.type === 'number_literal') {
                        evaluatedSize = parseInt(sizeLiteralNode.text);
                    } else {
                        evaluatedSize = evaluateSimpleExpression(sizeExprText);
                    }
                
                    if (declaredSize && evaluatedSize && evaluatedSize > declaredSize) {
                        issues.push(
                            `Warning: ${fnName} copying ${evaluatedSize} bytes into "${destBuffer}" (${declaredSize} bytes) in "${methodName}"`
                        );
                    }
                }
                if (fnName === 'strncpy') {
                    const dest = args[0];
                    const sizeArg = args[2];
                
                    // Validate size arg
                    const isValidated = validationChecks.has(sizeArg) || /sizeof|strlen/.test(sizeArg);
                
                    if (!isValidated) {
                        issues.push(`Warning: Unvalidated size parameter in strncpy to "${dest}" in "${methodName}"`);
                    }
                
                    // Check literal overflow if destination is known
                    if (buffers.has(dest)) {
                        const bufferSize = buffers.get(dest)!;
                        const sizeValue = parseInt(sizeArg);
                        if (!isNaN(sizeValue) && sizeValue > bufferSize) {
                            issues.push(
                                `Warning: strncpy copies ${sizeValue} bytes into buffer "${dest}" (${bufferSize} bytes) in "${methodName}". May overflow.`
                            );
                        }
                    }
                }
                
                

                if (fnName) calledFunctions.add(fnName);
            }

            //  Recursion Detection
            if (node.type === 'call_expression' && node.child(0)?.text === methodName) {
                const bufferNames = Array.from(buffers.keys()).join(', ');
                if (bufferNames) {
                    issues.push(`Warning: Recursive function "${methodName}" with local buffers (${bufferNames})`);
                }
            }

            // Pointer Arithmetic
            // Detect pointer arithmetic on aliases
            console.log("Alias map:", aliases);

            // Pointer Arithmetic Detection (extended)
            if (
                node.type === 'augmented_assignment_expression' &&
                ['+=', '-='].includes(node.child(1)?.text || '')
            ) {
                const lhs = node.child(0);
                if (lhs?.type === 'identifier') {
                    const varName = lhs.text;
                    if (buffers.has(varName) || aliases.has(varName) || mallocAssigned.has(varName)) {
                        const origin = buffers.get(varName) ? varName : aliases.get(varName) || 'unknown';
                        issues.push(`Warning: Pointer arithmetic on buffer or pointer "${varName}" (→ ${origin}) in "${methodName}"`);
                    }
                }
            }

            // Handle pointer = buffer + offset;
            if (
                node.type === 'assignment_expression'
            ) {
                const rhsNode = node.child(2);
                if (
                    rhsNode &&
                    rhsNode.type === 'binary_expression'
                ) {
                    const operatorNode = rhsNode.child(1);
                    if (operatorNode && ['+', '-'].includes(operatorNode.text)) {
                        const lhs = node.child(0);
                        const rhsLeft = rhsNode.child(0);
                        const rhsRight = rhsNode.child(2);
                        if (
                            lhs?.type === 'identifier' &&
                            rhsLeft?.type === 'identifier'
                        ) {
                            const base = rhsLeft.text;
                            const target = lhs.text;
                            if (buffers.has(base) || aliases.has(base) || mallocAssigned.has(base)) {
                                const origin = buffers.has(base) ? base : aliases.get(base) || 'unknown';
                                issues.push(`Warning: Pointer "${target}" assigned with arithmetic on "${base}" (→ ${origin}) in "${methodName}"`);
                            }
                        }
                    }
                }
            }
            

            // Handle *(ptr + N) dereference
            if (
                node.type === 'unary_expression' &&
                node.text.startsWith('*(') &&
                node.namedChildCount === 1 &&
                node.firstNamedChild?.type === 'binary_expression'
            ) {
                const binary = node.firstNamedChild;
                const left = binary.child(0);
                const right = binary.child(2);
                const op = binary.child(1)?.text;

                if (op && ['+', '-'].includes(op) && left?.type === 'identifier') {
                    const ptr = left.text;
                    if (buffers.has(ptr) || aliases.has(ptr) || mallocAssigned.has(ptr)) {
                        const origin = buffers.has(ptr) ? ptr : aliases.get(ptr) || 'unknown';
                        issues.push(`Warning: Pointer arithmetic dereference on "${ptr}" (→ ${origin}) in "${methodName}"`);
                    }
                }
            }


            

            // Index Validation
            if (node.type === 'subscript_expression') {
                const buffer = node.namedChild(0)?.text;
                const indexNode = node.namedChild(1);
                const index = indexNode?.text;
            
                if (buffer && index) {
                    const isLiteral = indexNode.type === 'number_literal';
            
                    if (!isLiteral && !validationChecks.has(index)) {
                        issues.push(`Warning: Unvalidated index "${index}" used with "${buffer}" in "${methodName}"`);
                    }
            
                    // Optional: warn if index constant exceeds buffer size
                    if (isLiteral && buffers.has(buffer)) {
                        const maxIndex = parseInt(index);
                        const bufSize = buffers.get(buffer)!;
                        if (maxIndex >= bufSize) {
                            issues.push(`Warning: Index "${maxIndex}" exceeds buffer size (${bufSize}) for "${buffer}" in "${methodName}"`);
                        }
                    }
                }
            }
            

            //node.namedChildren.forEach(traverse);
        }


        
         // Fallback: detect numeric validations in conditions like `if (size < 1024)`
         const numericCheckRegex = /\bif\s*\((.*?)\)/gs; // Use `s` flag to allow multiline
         let numericMatch: RegExpExecArray | null;
 
         while ((numericMatch = numericCheckRegex.exec(methodBody)) !== null) {
             const condition = numericMatch[1];
 
             // Heuristics: must include number & comparison operator
             if (/[<>!=]=?/.test(condition) && /\b\d+\b/.test(condition)) {
                 const varMatches = condition.match(/\b\w+\b/g);
                 for (const v of varMatches || []) {
                     if (!['if', 'while', 'for', 'sizeof', 'strlen'].includes(v)) {
                         validationChecks.add(v);
                     }
                 }
             }
         }
 
         console.log("Validation checks:", Array.from(validationChecks));
 
        traverse(tree.rootNode);


       

        

        // Hybrid Fallback Regex for Complex Conditional Checks
        const hybridRegex = /(?:\b(?:if|while|for)\s*\(|&&|\|\|).*?\b(?:strlen|sizeof|_countof)\s*\(\s*(\w+)\s*\).*?(?:\)|;)/g;
        let match: RegExpExecArray | null;
        while ((match = hybridRegex.exec(methodBody)) !== null) {
            validationChecks.add(match[1]);
        }

        return issues;
    }
}
