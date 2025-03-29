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
            //  Buffer Declarations
            if (node.type === 'init_declarator') {
                const declaratorNode = node.childForFieldName('declarator');
                const valueNode = node.childForFieldName('value');
            
                if (declaratorNode && valueNode) {
                    // Get identifier from pointer_declarator or direct
                    const identifier = declaratorNode.descendantsOfType('identifier')[0];
                    const lhsName = identifier?.text || null;
                    const rhsName = valueNode.text || null;
            
                    // 🌟 Track simple alias like: char *a = buf;
                    if (lhsName && rhsName && buffers.has(rhsName)) {
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

            // Track variables checked with: if (ptr)
            if (node.type === 'if_statement') {
                const cond = node.childForFieldName('condition');
                if (cond?.type === 'identifier') {
                    mallocChecked.add(cond.text);
                    validationChecks.add(cond.text); // Treat the checked malloc'd pointer as validated
                }
            }
           
            //  Call Expression Handling
            if (node.type === 'call_expression') {
                const fnName = node.child(0)?.text;
                const args = node.child(1)?.namedChildren.map(c => c.text) || [];

                // Validation tracking
                if (['strlen', 'sizeof', '_countof'].includes(fnName || '')) {
                    args.forEach(arg => validationChecks.add(arg));
                }

                // Unvalidated risky function usage + literal overflow check
                if (['strcpy', 'gets', 'sprintf'].includes(fnName || '')) {
                    const buffer = args[0];
                    const source = args[1];

                    if (
                        buffer &&
                        !validationChecks.has(buffer) &&
                        !isValidatedByFunction(buffer) &&
                        !mallocChecked.has(buffer)
                    ) {
                        issues.push(`Warning: Unvalidated ${fnName} usage with "${buffer}" in "${methodName}"`);
                    }
                    

                    // Literal overflow detection (e.g., strcpy(buf, "too long literal"))
                    if (
                        buffer &&
                        source &&
                        buffers.has(buffer) &&
                        node.child(1)?.namedChildren?.[1]?.type === 'string_literal'
                    ) {
                        const literal = node.child(1)?.namedChildren?.[1]?.text || '';
                        const literalLength = literal.length - 2; // subtract quotes
                        const declaredSize = buffers.get(buffer);
                        if (declaredSize !== undefined && literalLength > declaredSize) {
                            issues.push(
                                `Warning: String literal of length ${literalLength} copied into buffer "${buffer}" (${declaredSize} bytes) in "${methodName}". May overflow.`
                            );
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
                    if (!validationChecks.has(sizeArg)) {
                        issues.push(`Warning: Untrusted allocation size "${sizeArg}" in "${methodName}"`);
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
            

            node.namedChildren.forEach(traverse);
        }

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
