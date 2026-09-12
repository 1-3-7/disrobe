interface Entity {
    readonly id: number;
    readonly name: string;
    readonly [extra: string]: unknown;
}

abstract class Repository<T extends Entity> {
    protected readonly items: Map<number, T> = new Map<number, T>();

    protected abstract validate(item: T): void;

    insert(item: T): void {
        this.validate(item);
        if (this.items.has(item.id)) {
            throw new Error(`duplicate id ${item.id}`);
        }
        this.items.set(item.id, item);
    }

    get(id: number): T | undefined {
        return this.items.get(id);
    }

    list(): ReadonlyArray<T> {
        return [...this.items.values()];
    }

    protected count(): number {
        return this.items.size;
    }
}

interface User extends Entity {
    readonly email: string;
    readonly verified: boolean;
}

class UserRepository extends Repository<User> {
    private readonly emailIndex: Map<string, number> = new Map<string, number>();

    protected validate(item: User): void {
        if (!item.email.includes("@")) {
            throw new Error(`invalid email: ${item.email}`);
        }
    }

    insert(item: User): void {
        super.insert(item);
        this.emailIndex.set(item.email, item.id);
    }

    findByEmail(email: string): User | undefined {
        const id = this.emailIndex.get(email);
        return id === undefined ? undefined : this.get(id);
    }

    verifiedCount(): number {
        let n = 0;
        for (const u of this.items.values()) {
            if (u.verified) {
                n += 1;
            }
        }
        return n;
    }

    totalCount(): number {
        return this.count();
    }
}

const repo = new UserRepository();
repo.insert({ id: 1, name: "alice", email: "alice@example.com", verified: true });
repo.insert({ id: 2, name: "bob", email: "bob@example.com", verified: false });
console.log(repo.verifiedCount(), repo.totalCount(), repo.findByEmail("alice@example.com")?.name);
