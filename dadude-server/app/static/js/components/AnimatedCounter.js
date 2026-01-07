// Animated Counter Component per Vue.js 3
// Animazione smooth per numeri

const AnimatedCounter = {
    props: {
        value: {
            type: Number,
            required: true,
            default: 0
        },
        duration: {
            type: Number,
            default: 1000
        },
        decimals: {
            type: Number,
            default: 0
        }
    },
    data() {
        return {
            displayValue: 0,
            animationFrame: null
        }
    },
    mounted() {
        this.animate();
    },
    watch: {
        value() {
            this.animate();
        }
    },
    beforeUnmount() {
        if (this.animationFrame) {
            cancelAnimationFrame(this.animationFrame);
        }
    },
    methods: {
        animate() {
            const startValue = this.displayValue;
            const endValue = this.value;
            const startTime = performance.now();
            const duration = this.duration;
            
            const animate = (currentTime) => {
                const elapsed = currentTime - startTime;
                const progress = Math.min(elapsed / duration, 1);
                
                // Easing function (ease-out)
                const easeOut = 1 - Math.pow(1 - progress, 3);
                
                this.displayValue = Math.floor(startValue + (endValue - startValue) * easeOut);
                
                if (progress < 1) {
                    this.animationFrame = requestAnimationFrame(animate);
                } else {
                    this.displayValue = endValue;
                }
            };
            
            this.animationFrame = requestAnimationFrame(animate);
        },
        formatValue(value) {
            if (this.decimals > 0) {
                return value.toFixed(this.decimals);
            }
            return value.toLocaleString('it-IT');
        }
    },
    template: `
        <span>{{ formatValue(displayValue) }}</span>
    `
};

