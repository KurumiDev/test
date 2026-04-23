package dev.kurumi.obfuscator.retrace;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RetraceToolTest {

    @Test
    void invertsClassAndMethodNames() {
        String mapping = """
                com/example/Plugin -> o/a
                    onEnable()V -> b
                    process(I)V -> c
                com/example/Util -> o/d
                    helper()V -> e
                """;
        RetraceTool tool = new RetraceTool(mapping);
        String trace = """
                java.lang.RuntimeException: boom
                \tat o.a.b(Unknown Source)
                \tat o.a.c(Unknown Source)
                \tat o.d.e(Unknown Source)
                """;
        String out = tool.retrace(trace);
        assertEquals(true, out.contains("com.example.Plugin.onEnable(Unknown Source)"));
        assertEquals(true, out.contains("com.example.Plugin.process(Unknown Source)"));
        assertEquals(true, out.contains("com.example.Util.helper(Unknown Source)"));
    }
}
