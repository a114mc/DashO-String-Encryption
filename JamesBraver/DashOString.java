package me.iris.ambien.obfuscator.transformers.impl.data.string;

import me.iris.ambien.obfuscator.asm.SizeEvaluator;
import me.iris.ambien.obfuscator.builders.MethodBuilder;
import me.iris.ambien.obfuscator.utilities.GOTOASMUtils;
import me.iris.ambien.obfuscator.utilities.MathUtil;
import me.iris.ambien.obfuscator.utilities.kek.myj2c.Myj2cASMUtils;
import me.iris.ambien.obfuscator.utilities.string.StringUtil;
import org.objectweb.asm.Label;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class DashOString implements Opcodes {
    private static final String descriptor =
            "(IILjava/lang/String;)Ljava/lang/String;";    // int int String -> String

    private static String methodName = "waiting for an update...";

    public static void process(ClassNode classNode) {
        pre:
        {
            methodName = StringUtil.randomIllegalJavaName();
        }
        boolean shouldRemove = true;

        for (MethodNode method : classNode.methods) {

            // Skip the decrypt method itself and empty methods
            if (method.name.equals(
                    methodName) || method.instructions == null || method.instructions.size() == 0) {
                continue;
            }

            InsnList insns = method.instructions;
            if (SizeEvaluator.willOverflow(method, insns)) {
                continue;
            }

            for (AbstractInsnNode insn : insns.toArray()) { // Use toArray() to avoid concurrent modification
                if (insn instanceof LdcInsnNode) {
                    LdcInsnNode ldc = (LdcInsnNode) insn;
                    if (ldc.cst instanceof String) {
                        // Do not process empty string calls
                        if (((String) ldc.cst).isEmpty()) {
                            continue;
                        }
                        shouldRemove = false;
                        processStringConstant(classNode, method, insns, ldc);
                    }
                } else if (insn instanceof InvokeDynamicInsnNode) {
                    InvokeDynamicInsnNode invokeDynamic = (InvokeDynamicInsnNode) insn;
                    if (isStringConcatFactory(invokeDynamic)) {
                        shouldRemove = !processInvokeDynamic(
                                classNode, method, insns,
                                invokeDynamic
                        );
                    }
                }
            }
        }

        doing:
        {
            injectDecryptMethod(classNode); // Ensure decrypt method exists
        }
        post:
        {
            if (shouldRemove) {
                removeDecryptMethod(classNode);
            }
        }
    }

    private static boolean isStringConcatFactory(InvokeDynamicInsnNode invokeDynamic) {
        return "makeConcatWithConstants".equals(
                invokeDynamic.name) && "java/lang/invoke/StringConcatFactory".equals(
                invokeDynamic.bsm.getOwner());
    }

    private static void processStringConstant(ClassNode classNode, MethodNode method, InsnList insns, LdcInsnNode ldc) {
        String original = (String) ldc.cst;
        processString(classNode, method, insns, ldc, original);
    }

    private static boolean processInvokeDynamic(ClassNode classNode, MethodNode method,
                                                InsnList insns, InvokeDynamicInsnNode invokeDynamic
    ) {
        boolean processed = false;
        for (Object arg : invokeDynamic.bsmArgs) {
            if (arg instanceof String) {
                String original = (String) arg;
                // Do not process empty string calls
                if (((String) arg).isEmpty()) {
                    continue;
                }
                processString(classNode, method, insns, invokeDynamic, original);
                processed = true;
            }
        }
        return processed;
    }

    private static void processString(ClassNode classNode, MethodNode method, InsnList insns, AbstractInsnNode node, String original) {
        int b = MathUtil.randomInt('\u3040', '\u309f');
        int c = MathUtil.randomInt(1, 127);
        String encrypted = encode(b, c, original);

        InsnList newList = new InsnList();
        newList.add(Myj2cASMUtils.pushInt(b));
        newList.add(Myj2cASMUtils.pushInt(c));
        newList.add(new LdcInsnNode(encrypted));
        newList.add(new MethodInsnNode(
                INVOKESTATIC, classNode.name, methodName,
                descriptor, false
        ));

        insns.insert(node, newList);
        insns.remove(node);
    }

    private static void removeDecryptMethod(ClassNode classNode) {
        classNode.methods.removeIf(
                method -> method.name.equals(methodName) && method.desc.equals(
                        descriptor));
    }

    /**
     * 注入一个私有静态解密方法到给定的 ClassNode 中。
     * 解密方法接收一个加密字符串，并返回解密后的字符串。
     * 解密密钥是根据调用者的类名和方法名动态生成的。
     * 此外，它根据输入字符串的长度自动生成不同的 extraXorKey。
     *
     * @author a114mc
     * @author ASMIfier
     */
    private static void injectDecryptMethod(ClassNode classNode) {
        // 检查解密方法是否已存在，防止重复注入
        for (MethodNode existingMethod : classNode.methods) {
            if (existingMethod.name.equals(methodName) && existingMethod.desc.equals(descriptor)) {
                return; // 方法已存在，无需注入
            }
        }

        // 定义方法访问标志和签名
        // 假设 'methodName' 和 'descriptor' 是预先定义的常量或字段
        MethodBuilder methodBuilder = MethodBuilder.builder()
                .name(methodName)
                .access(ACC_PRIVATE | ACC_STATIC)
                .desc(descriptor)
                .build();

        // 如果 GOTOASMUtils 需要，应用 synthetic 和 bridge 标志
        if (GOTOASMUtils.shouldMarkAsSynthetic(methodBuilder.buildNode())) {
            methodBuilder.addAccess(ACC_SYNTHETIC);
        }
        if (GOTOASMUtils.shouldMarkAsBridge(methodBuilder.buildNode())) {
            methodBuilder.addAccess(ACC_BRIDGE);
        }

        MethodNode methodVisitor = methodBuilder.buildNode();

        // --- Begin code ---
        methodVisitor.visitCode();
        Label label0 = new Label();
        methodVisitor.visitLabel(label0);
        methodVisitor.visitLineNumber(48, label0);
        methodVisitor.visitVarInsn(ALOAD, 2);
        methodVisitor.visitMethodInsn(
                INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false);
        methodVisitor.visitVarInsn(ASTORE, 3);
        Label label1 = new Label();
        methodVisitor.visitLabel(label1);
        methodVisitor.visitLineNumber(49, label1);
        methodVisitor.visitInsn(ICONST_0);
        methodVisitor.visitVarInsn(ISTORE, 4);
        Label label2 = new Label();
        methodVisitor.visitLabel(label2);
        methodVisitor.visitFrame(
                Opcodes.F_NEW,
                5,
                new Object[]{
                        Opcodes.INTEGER, Opcodes.INTEGER, "java/lang/String", "[C", Opcodes.INTEGER
                },
                0,
                new Object[]{});
        methodVisitor.visitVarInsn(ILOAD, 4);
        methodVisitor.visitVarInsn(ALOAD, 3);
        methodVisitor.visitInsn(ARRAYLENGTH);
        Label label3 = new Label();
        methodVisitor.visitJumpInsn(IF_ICMPGE, label3);
        Label label4 = new Label();
        methodVisitor.visitLabel(label4);
        methodVisitor.visitLineNumber(50, label4);
        methodVisitor.visitVarInsn(ALOAD, 3);
        methodVisitor.visitVarInsn(ILOAD, 4);
        methodVisitor.visitVarInsn(ALOAD, 3);
        methodVisitor.visitVarInsn(ILOAD, 4);
        methodVisitor.visitInsn(CALOAD);
        methodVisitor.visitVarInsn(ILOAD, 0);
        methodVisitor.visitIntInsn(BIPUSH, 95);
        methodVisitor.visitInsn(IAND);
        methodVisitor.visitInsn(IXOR);
        methodVisitor.visitInsn(I2C);
        methodVisitor.visitInsn(CASTORE);
        Label label5 = new Label();
        methodVisitor.visitLabel(label5);
        methodVisitor.visitLineNumber(51, label5);
        methodVisitor.visitVarInsn(ILOAD, 0);
        methodVisitor.visitVarInsn(ILOAD, 1);
        methodVisitor.visitInsn(IADD);
        methodVisitor.visitVarInsn(ISTORE, 0);
        Label label6 = new Label();
        methodVisitor.visitLabel(label6);
        methodVisitor.visitLineNumber(49, label6);
        methodVisitor.visitIincInsn(4, 1);
        methodVisitor.visitJumpInsn(GOTO, label2);
        methodVisitor.visitLabel(label3);
        methodVisitor.visitLineNumber(53, label3);
        methodVisitor.visitFrame(
                Opcodes.F_NEW,
                4,
                new Object[]{Opcodes.INTEGER, Opcodes.INTEGER, "java/lang/String", "[C"},
                0,
                new Object[]{});
        methodVisitor.visitTypeInsn(NEW, "java/lang/String");
        methodVisitor.visitInsn(DUP);
        methodVisitor.visitVarInsn(ALOAD, 3);
        methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false);
        methodVisitor.visitInsn(ARETURN);
        // 设置操作数栈和局部变量表的最大大小。
        // 使用 ClassWriter.COMPUTE_MAXS 会自动计算，更方便。
        methodVisitor.visitMaxs(0, 0); // Let ASM calculate all those shits
        methodVisitor.visitEnd();
        // Add the method to classNode.methods
        classNode.methods.add(methodVisitor);
    }


    /**
     * 对称加解密方法：输入相同参数 n 和 n2，可以加密和解密。
     *
     * @param n     default key
     * @param n2    step-in key
     * @param input input content(encrypted or plain text)
     * @return encrypted or plain text
     * @apiNote This method was optimized due to James Braver poops useless calculations inside it like
     * <pre><code>int n = 2 + 2;</code></pre>
     * .
     */
    public static String encode(int n, int n2, String input) {
        char[] chars = input.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) (chars[i] ^ (n & 95)); // 95 似乎是硬编码的掩码
            n += n2;
        }
        return new String(chars).intern();
    }
}